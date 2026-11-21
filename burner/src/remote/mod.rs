//! `burner -H HOST ...`: the same commands on another machine, over ssh. the
//! client only starts ssh, as you. burner on the far end runs as it would
//! there by hand; what it sends back is parsed and filtered here again, since
//! a compromised host shouldn't get to drive your terminal or your tar -x

pub mod hosts;
