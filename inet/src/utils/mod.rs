//! Network utilities

mod netstat;
pub use self::netstat::*;

mod switch;
pub use self::switch::*;

mod getip;
pub use self::getip::*;

// pub struct MergedTimer<Token, Identifier> {
//     identifier: Identifier,
//     scheduled: BTreeSet<SimTime>,
//     tokens: Vec<(Token, SimTime)>,
// }

// impl<Token, Identifier> MergedTimer<Token, Identifier>
// where
//     Token: Hash + Eq,
//     Identifier: PartialEq + Clone,
// {
//     pub const fn new(identifier: Identifier) -> Self {
//         MergedTimer {
//             identifier,
//             scheduled: BTreeSet::new(),
//             tokens: Vec::new(),
//         }
//     }

//     // # Upwards API

//     pub fn schedule(&mut self, token: Token, time: SimTime) {
//         assert!(time >= SimTime::now());
//         match self.tokens.binary_search_by_key(&time, |v| v.1) {
//             Ok(i) | Err(i) => self.tokens.insert(i, (token, time)),
//         }
//     }

//     pub fn reschedule(&mut self, token: &Token, time: SimTime)
//     where
//         Token: Clone,
//     {
//         assert!(time >= SimTime::now());
//         let Some(i) = self
//             .tokens
//             .iter()
//             .position(|(stored_token, _)| stored_token == token)
//         else {
//             return self.schedule(token.clone(), time);
//         };

//         let (stored_token, _) = self.tokens.remove(i);
//         self.schedule(stored_token, time);
//     }

//     pub fn cancel(&mut self, token: &Token) {
//         self.tokens.retain(|(stored, _)| stored != token);
//     }

//     pub fn inspect(&self, token: &Token) -> Option<SimTime> {
//         self.tokens.iter().find_map(|(stored_token, time)| {
//             if stored_token == token {
//                 Some(*time)
//             } else {
//                 None
//             }
//         })
//     }

//     // # Downwards API

//     pub fn next_wakeup(&self) -> Option<SimTime> {
//         self.tokens.first().map(|(_, time)| *time)
//     }

//     pub fn register(&mut self) -> Option<(Identifier, SimTime)> {
//         let t = self.next_wakeup()?;
//         self.scheduled.insert(t);
//         Some((self.identifier.clone(), t))
//     }

//     pub fn register_into_other<I>(&mut self, other: &mut MergedTimer<Identifier, I>)
//     where
//         I: PartialEq + Clone,
//         Identifier: Hash + Eq,
//     {
//         if let Some((my_token, time)) = self.register() {
//             other.reschedule(&my_token, time);
//         }
//     }

//     pub fn on_wakeup(&mut self, mut f: impl FnMut(Token)) {
//         let now = SimTime::now();

//         // (0) Remove from scheduled queue
//         while let Some(sched) = self.scheduled.first() {
//             if sched <= &now {
//                 self.scheduled.pop_first();
//             } else {
//                 break;
//             }
//         }

//         // (1) Colllect the activations
//         while let Some((_, t)) = self.tokens.first() {
//             if t <= &now {
//                 f(self.tokens.remove(0).0);
//             } else {
//                 break;
//             }
//         }
//     }
// }
