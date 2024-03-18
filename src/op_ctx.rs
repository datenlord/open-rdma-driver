use std::{
    sync::{Arc, Mutex},
    thread::{self, Thread},
};

/// The status of operations.
#[derive(Debug, Clone)]
/// The status of operations.
pub enum CtxStatus {
    /// The operation is invalid.
    Invalid,
    /// The operation is running.
    Running,
    /// The operation is stopped.
    Failed(&'static str),
    /// The operation is finished.
    Finished,
}

#[derive(Debug, Clone)]
pub struct OpCtx<Payload>(Arc<Mutex<OpCtxInner<Payload>>>);

#[derive(Debug)]
pub struct OpCtxInner<Payload> {
    thread: Option<Thread>,
    status: CtxStatus,
    payload: Option<Payload>,
}

pub type CtrlOpCtx = OpCtx<bool>; // `is_sucess`
pub type WriteOpCtx = OpCtx<()>;
pub type ReadOpCtx = OpCtx<()>;

impl<Payload> OpCtx<Payload> {
    pub fn new_running() -> Self {
        let inner = OpCtxInner {
            thread: None,
            status: CtxStatus::Running,
            payload: None,
        };
        Self(Arc::new(Mutex::new(inner)))
    }

    pub fn wait(&self) {
        let mut guard = self.0.lock().unwrap();
        if matches!(guard.status, CtxStatus::Running) {
            guard.thread = Some(thread::current());
            drop(guard);
            thread::park();
        }
    }

    pub(crate) fn set_result(&self, result: Payload) {
        let mut guard = self.0.lock().unwrap();
        guard.payload = Some(result);
        guard.status = CtxStatus::Finished;
        if let Some(thread) = guard.thread.take() {
            thread.unpark();
        }
    }

    pub fn get_status(&self) -> CtxStatus {
        self.0.lock().unwrap().status.clone()
    }
}

impl<Payload: Clone> OpCtx<Payload> {
    pub fn wait_result(&self) -> Option<Payload>{
        self.wait();
        let guard = self.0.lock().unwrap();
        guard.payload.clone()
    }
    
    pub fn get_result(&self) -> Option<Payload> {
        let guard = self.0.lock().unwrap();
        guard.payload.clone()
    }
}


#[cfg(test)]
mod tests{
    #[test]
    fn test_op_ctx() {
        let ctx = super::OpCtx::new_running();
        let ctx_clone = ctx.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            ctx_clone.set_result(true);
        });
        ctx.wait();
        assert_eq!(ctx.get_result(), Some(true));

        let ctx = super::OpCtx::new_running();
        let ctx_clone = ctx.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(10));
            ctx_clone.set_result(false);
        });
        ctx.wait_result();
        assert_eq!(ctx.get_result(), Some(false));
    }
}