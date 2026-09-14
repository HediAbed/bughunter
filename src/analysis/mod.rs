pub mod static_checks;

pub use static_checks::{
    StaticAnalysis, run_static_checks_with_inventory, run_static_checks_with_inventory_cancellable,
};
