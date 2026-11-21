//! F3d: leaving a group, and hearing that another member left.
//!
//! `leave` takes effect in memory at once: the group vanishes from the handle's output and the
//! handle neither votes nor shows messages for it. The departure is durable and reported (`Left`)
//! only after a confirmed save; a crash before that write loses the leave. Agreement on the
//! shared roster comes later and never undoes the local leave: this slice stages the signed
//! departure for the other members and records the ones it receives, but does not yet change a
//! shared roster.

use super::*;

impl GroupHandle {
    /// Leave `group_id`. Signs a departure for the current roster and stages it for the other
    /// members. The host must save and confirm before treating the leave as safe.
    pub fn leave(&mut self, group_id: u64, now: u64) -> Result<OpId, HandleError> {
        self.ensure_local_views()?;
        self.register_local(group_id);
        self.expire(now);
        self.check_room()?;
        if self
            .left
            .contains(&(self.installation.selected(), group_id))
        {
            return Err(HandleError::Unknown);
        }
        let me = self.installation.selected();
        let group = self
            .groups
            .get(&(self.installation.selected(), group_id))
            .ok_or(HandleError::Unknown)?;
        let tenure = group.membership(me).ok_or(HandleError::Ineligible)?;
        let members = group
            .export_roster(&self.installation)
            .map_err(|_| HandleError::Ineligible)?
            .members;
        let departure = SignedDeparture::new(
            group.departure_context(me).ok_or(HandleError::Ineligible)?,
            &self.installation,
        )
        .map_err(|_| HandleError::Ineligible)?;
        let bytes = encode_frame(Tag::Departure, &departure.to_bytes())
            .map_err(|_| HandleError::Invalid)?;
        self.local
            .leave(tenure)
            .map_err(|_| HandleError::Ineligible)?;
        self.left.insert((me, group_id));
        self.forget_group(group_id);
        let outgoing = vec![Outgoing {
            from: self.installation.selected(),
            to: members.into_iter().filter(|key| *key != me).collect(),
            kind: Tag::Departure,
            bytes,
            authenticator: None,
        }];
        Ok(self.stage(outgoing, vec![Event::Left(group_id)]))
    }

    /// Drop everything in flight for a group we no longer take part in.
    fn forget_group(&mut self, group_id: u64) {
        let sent: Vec<LocalBinding> = self
            .sent
            .iter()
            .filter(|((owner, _), s)| *owner == self.installation.selected() && s.group == group_id)
            .map(|(b, _)| *b)
            .collect();
        for binding in sent {
            if let Some(record) = self.sent.remove(&binding) {
                self.reject_if_pending(record.op, Reason::Stale);
            }
        }
        self.observed
            .retain(|(owner, _), o| *owner != self.installation.selected() || o.group != group_id);
        self.rounds
            .retain(|(owner, _), r| *owner != self.installation.selected() || r.group != group_id);
        self.strays
            .retain(|s| s.owner != self.installation.selected() || s.group != group_id);
    }

    /// A member says they left. Check the signature and the tenure against our roster, keep
    /// the signed bytes, and report it. The roster itself does not change here.
    pub(super) fn receive_departure(&mut self, from: Key, body: &[u8]) -> Result<(), Reason> {
        let departure = SignedDeparture::from_bytes(body).map_err(|_| Reason::Malformed)?;
        if departure.member() != from {
            return Err(Reason::Invalid);
        }
        let group_id = departure.context().0;
        if self
            .left
            .contains(&(self.installation.selected(), group_id))
        {
            return Ok(());
        }
        let group = self
            .groups
            .get(&(self.installation.selected(), group_id))
            .ok_or(Reason::Unknown)?;
        group
            .signed_departure_child(&departure)
            .map_err(|_| Reason::Stale)?;
        if self
            .departures
            .contains_key(&(self.installation.selected(), group_id, from))
        {
            return Ok(());
        }
        if self.departures.len() >= MAX_DEPARTURES || self.staged.len() >= MAX_STAGED_ITEMS {
            return Err(Reason::Full);
        }
        self.departures.insert(
            (self.installation.selected(), group_id, from),
            body.to_vec(),
        );
        self.push_item(
            None,
            Vec::new(),
            vec![Event::MemberDeparted {
                group: group_id,
                member: from,
            }],
            false,
        );
        Ok(())
    }
}
