use crate::{Device, Error, Mr, Qp};
use rand::RngCore as _;
use std::{
    collections::HashSet,
    hash::{Hash, Hasher},
};

// TODO: PD will be shared by multi function call. Use reference counter?
#[derive(Debug, Clone)]
pub struct Pd {
    pub(crate) handle: u32,
}

pub(crate) struct PdCtx {
    pub(crate) mr: HashSet<Mr>,
    pub(crate) qp: HashSet<Qp>,
}

impl Device {
    pub fn alloc_pd(&self) -> Result<Pd, Error> {
        let mut pool = self.0.pd.lock().unwrap();

        let pd = Pd {
            handle: rand::thread_rng().next_u32(),
        };

        let res = pool.insert(
            pd.clone(),
            PdCtx {
                mr: HashSet::new(),
                qp: HashSet::new(),
            },
        );

        assert!(res.is_none());

        Ok(pd)
    }

    pub fn dealloc_pd(&self, pd: Pd) -> Result<(), Error> {
        let mut pool = self.0.pd.lock().unwrap();
        let pd_ctx = pool.get(&pd).ok_or(Error::InvalidPd)?;

        if !pd_ctx.mr.is_empty() {
            return Err(Error::PdInUse);
        }

        if !pd_ctx.qp.is_empty() {
            return Err(Error::QpInUse);
        }

        pool.remove(&pd);

        Ok(())
    }
}

impl Hash for Pd {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.handle.hash(state);
    }
}

impl PartialEq for Pd {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
    }
}

impl Eq for Pd {}
