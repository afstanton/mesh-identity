//! G3b-1: reading a source view and consenting to a formation, from the handle's own groups.
//!
//! Neither call changes handle state or stages anything. A consent is a signature over one exact
//! formation; it takes no lock and no counter, so it does not go through the outbox. The host
//! carries the 96 bytes however it likes, and the views are built here, from groups this handle
//! verified, so the app cannot hand in a view it got wrong.

use super::*;
use crate::groups::merge::{Formation, FormationConsent, SourceView};

impl GroupHandle {
    /// A view of a group this identity belongs to. `None` for a group it does not hold, has left,
    /// or has only been invited to.
    pub fn source_view(&self, group_id: u64) -> Option<SourceView> {
        self.group(group_id).map(SourceView::from_group)
    }

    /// Consent to `formation` as the selected identity, from the groups this handle holds now.
    /// Refuses (`Formation(StaleSource)`) unless one of them is exactly a source of the proposal,
    /// and when a held group the proposal names has moved on since. A gated device, or an identity
    /// outside the final roster, gets `Formation(Cannot)`.
    pub fn consent_to_formation(
        &self,
        formation: &Formation,
    ) -> Result<FormationConsent, HandleError> {
        let views: Vec<SourceView> = self
            .group_ids()
            .into_iter()
            .filter_map(|id| self.source_view(id))
            .collect();
        formation
            .consent_from(&self.installation, &views)
            .map_err(HandleError::Formation)
    }
}

impl GroupHandle {
    /// Take the group `formation` created, once every member of its final roster has signed.
    ///
    /// The group is stored like an imported genesis (its history starts from the agreed genesis),
    /// together with the signed proposal, so it can show where it came from. `GroupFormed` is
    /// released after the confirmed save; a crash before that write loses the adoption and a
    /// repeat gives the identical group. The source groups are neither read nor changed. A group
    /// this identity already holds, or left, under the derived id is refused with `Duplicate`.
    pub fn adopt_formation(&mut self, formation: &Formation) -> Result<OpId, HandleError> {
        self.check_room()?;
        if self.groups.len() >= MAX_GROUPS {
            return Err(HandleError::Full);
        }
        let me = self.installation.selected();
        let formed = formation.complete().map_err(HandleError::Formation)?;
        if formed.group.membership(me).is_none() {
            return Err(HandleError::Ineligible);
        }
        let id = formed.group.id();
        if self.groups.contains_key(&(me, id)) || self.left.contains(&(me, id)) {
            return Err(HandleError::Duplicate);
        }
        let genesis = formed
            .group
            .genesis_bytes()
            .map_err(|_| HandleError::Invalid)?;
        let proposal = formation.proposal().to_bytes();
        if proposal.len() > MAX_FRAME_BYTES {
            return Err(HandleError::TooLarge);
        }
        self.histories
            .insert((me, id), joining::History::new(genesis));
        self.groups.insert((me, id), formed.group);
        self.formed.insert(
            (me, id),
            FormedFrom {
                binding: formation.binding(),
                proposal,
            },
        );
        self.register_local(id);
        Ok(self.stage(Vec::new(), vec![Event::GroupFormed(id)]))
    }

    /// The signed proposal a formed group came from, for a group this identity holds.
    pub fn formed_from(&self, group_id: u64) -> Option<&[u8]> {
        self.group(group_id)?;
        self.formed
            .get(&(self.installation.selected(), group_id))
            .map(|record| record.proposal.as_slice())
    }
}
