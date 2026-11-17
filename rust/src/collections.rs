//! The core's maps: std's and indexmap's, and without std one small map on a `Vec`.
//!
//! Without std the maps are [`VecMap`] and [`VecSet`]: a linear scan over a few entries, so that a
//! firmware image carries one short copy of map code per key and value type in place of
//! hashbrown's, indexmap's and the B-tree's. `IndexMap`, `HashMap` and `HashSet` keep their
//! entries in insertion order, as indexmap does; `BTreeMap` and `BTreeSet` keep them sorted.

#[cfg(feature = "std")]
pub use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "std")]
pub use std::collections::{HashMap, HashSet};
#[cfg(feature = "std")]
pub type IndexMap<K, V> = indexmap::IndexMap<K, V>;

#[cfg(not(feature = "std"))]
pub use vec_map::{VecMap, VecSet};
#[cfg(not(feature = "std"))]
pub type HashMap<K, V> = VecMap<K, V>;
#[cfg(not(feature = "std"))]
pub type HashSet<K> = VecSet<K>;
#[cfg(not(feature = "std"))]
pub type IndexMap<K, V> = VecMap<K, V>;
#[cfg(not(feature = "std"))]
pub type BTreeMap<K, V> = VecMap<K, V, true>;
#[cfg(not(feature = "std"))]
pub type BTreeSet<K> = VecSet<K, true>;

/// Sorts `v`; without std by insertion, to keep core's sort code, a copy per type, out.
pub fn sort<T: Ord>(v: &mut [T]) {
    #[cfg(feature = "std")]
    v.sort();
    // shortcut: quadratic, fine for the few members and indexes a group has; use v.sort() if that grows.
    #[cfg(not(feature = "std"))]
    for i in 1..v.len() {
        let mut j = i;
        while j > 0 && v[j - 1] > v[j] {
            v.swap(j - 1, j);
            j -= 1;
        }
    }
}

#[cfg(not(feature = "std"))]
mod vec_map {
    use crate::prelude::*;
    use core::borrow::Borrow;
    use core::fmt;

    /// A map on a `Vec` of pairs, in insertion order, or sorted by key when `SORTED`.
    #[derive(Clone)]
    pub struct VecMap<K, V, const SORTED: bool = false>(Vec<(K, V)>);

    /// A set on a [`VecMap`].
    #[derive(Clone, Default)]
    pub struct VecSet<K, const SORTED: bool = false>(VecMap<K, (), SORTED>);

    impl<K, V, const S: bool> Default for VecMap<K, V, S> {
        fn default() -> Self {
            VecMap(Vec::new())
        }
    }

    impl<K, V, const S: bool> VecMap<K, V, S> {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
        pub fn clear(&mut self) {
            self.0.clear()
        }
        pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> + ExactSizeIterator {
            self.0.iter().map(|(k, v)| (k, v))
        }
        pub fn iter_mut(
            &mut self,
        ) -> impl DoubleEndedIterator<Item = (&K, &mut V)> + ExactSizeIterator {
            self.0.iter_mut().map(|(k, v)| (&*k, v))
        }
        pub fn keys(&self) -> impl DoubleEndedIterator<Item = &K> + ExactSizeIterator {
            self.0.iter().map(|(k, _)| k)
        }
        pub fn values(&self) -> impl DoubleEndedIterator<Item = &V> + ExactSizeIterator {
            self.0.iter().map(|(_, v)| v)
        }
        pub fn values_mut(
            &mut self,
        ) -> impl DoubleEndedIterator<Item = &mut V> + ExactSizeIterator {
            self.0.iter_mut().map(|(_, v)| v)
        }
        pub fn first(&self) -> Option<(&K, &V)> {
            self.0.first().map(|(k, v)| (k, v))
        }
        pub fn last(&self) -> Option<(&K, &V)> {
            self.0.last().map(|(k, v)| (k, v))
        }
        pub fn retain(&mut self, mut f: impl FnMut(&K, &mut V) -> bool) {
            self.0.retain_mut(|(k, v)| f(k, v))
        }
    }

    impl<K: Eq, V, const S: bool> VecMap<K, V, S> {
        fn find<Q: Eq + ?Sized>(&self, k: &Q) -> Option<usize>
        where
            K: Borrow<Q>,
        {
            self.0.iter().position(|(x, _)| x.borrow() == k)
        }
        pub fn get<Q: Eq + ?Sized>(&self, k: &Q) -> Option<&V>
        where
            K: Borrow<Q>,
        {
            self.find(k).map(|i| &self.0[i].1)
        }
        pub fn get_mut<Q: Eq + ?Sized>(&mut self, k: &Q) -> Option<&mut V>
        where
            K: Borrow<Q>,
        {
            self.find(k).map(|i| &mut self.0[i].1)
        }
        pub fn contains_key<Q: Eq + ?Sized>(&self, k: &Q) -> bool
        where
            K: Borrow<Q>,
        {
            self.find(k).is_some()
        }
        /// Removes `k`, keeping the others in order, as indexmap's `shift_remove`.
        pub fn remove<Q: Eq + ?Sized>(&mut self, k: &Q) -> Option<V>
        where
            K: Borrow<Q>,
        {
            self.find(k).map(|i| self.0.remove(i).1)
        }
        pub fn shift_remove<Q: Eq + ?Sized>(&mut self, k: &Q) -> Option<V>
        where
            K: Borrow<Q>,
        {
            self.remove(k)
        }
    }

    /// Where a new key goes: at the end, or in key order when sorted.
    pub trait Place<K> {
        fn place(&self, k: &K) -> usize;
    }
    impl<K, V> Place<K> for VecMap<K, V, false> {
        fn place(&self, _: &K) -> usize {
            self.0.len()
        }
    }
    impl<K: Ord, V> Place<K> for VecMap<K, V, true> {
        fn place(&self, k: &K) -> usize {
            self.0.partition_point(|(x, _)| x < k)
        }
    }

    impl<K: Eq, V, const S: bool> VecMap<K, V, S>
    where
        Self: Place<K>,
    {
        /// Inserts or replaces; a replaced key keeps its place.
        pub fn insert(&mut self, k: K, v: V) -> Option<V> {
            match self.find(&k) {
                Some(i) => Some(core::mem::replace(&mut self.0[i].1, v)),
                None => {
                    let i = self.place(&k);
                    self.0.insert(i, (k, v));
                    None
                }
            }
        }
        pub fn entry(&mut self, k: K) -> Entry<'_, K, V, S> {
            Entry { map: self, key: k }
        }
    }

    pub struct Entry<'a, K, V, const S: bool> {
        map: &'a mut VecMap<K, V, S>,
        key: K,
    }

    impl<'a, K: Eq, V, const S: bool> Entry<'a, K, V, S>
    where
        VecMap<K, V, S>: Place<K>,
    {
        pub fn or_insert_with(self, f: impl FnOnce() -> V) -> &'a mut V {
            let i = match self.map.find(&self.key) {
                Some(i) => i,
                None => {
                    let i = self.map.place(&self.key);
                    self.map.0.insert(i, (self.key, f()));
                    i
                }
            };
            &mut self.map.0[i].1
        }
        pub fn or_insert(self, v: V) -> &'a mut V {
            self.or_insert_with(|| v)
        }
        pub fn or_default(self) -> &'a mut V
        where
            V: Default,
        {
            self.or_insert_with(V::default)
        }
    }

    /// Equal when both hold the same pairs, in any order, as indexmap's and std's maps.
    impl<K: Eq, V: PartialEq, const S: bool> PartialEq for VecMap<K, V, S> {
        fn eq(&self, o: &Self) -> bool {
            self.len() == o.len() && self.iter().all(|(k, v)| o.get(k) == Some(v))
        }
    }
    impl<K: Eq, V: Eq, const S: bool> Eq for VecMap<K, V, S> {}

    impl<K: fmt::Debug, V: fmt::Debug, const S: bool> fmt::Debug for VecMap<K, V, S> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_map().entries(self.iter()).finish()
        }
    }

    impl<K: Eq, V, const S: bool> Extend<(K, V)> for VecMap<K, V, S>
    where
        Self: Place<K>,
    {
        fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, it: I) {
            for (k, v) in it {
                self.insert(k, v);
            }
        }
    }
    impl<K: Eq, V, const S: bool> FromIterator<(K, V)> for VecMap<K, V, S>
    where
        Self: Place<K>,
    {
        fn from_iter<I: IntoIterator<Item = (K, V)>>(it: I) -> Self {
            let mut m = Self::default();
            m.extend(it);
            m
        }
    }
    impl<K: Eq, V, const N: usize, const S: bool> From<[(K, V); N]> for VecMap<K, V, S>
    where
        Self: Place<K>,
    {
        fn from(a: [(K, V); N]) -> Self {
            a.into_iter().collect()
        }
    }
    impl<K, V, const S: bool> IntoIterator for VecMap<K, V, S> {
        type Item = (K, V);
        type IntoIter = alloc::vec::IntoIter<(K, V)>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }
    impl<'a, K, V, const S: bool> IntoIterator for &'a VecMap<K, V, S> {
        type Item = (&'a K, &'a V);
        type IntoIter =
            core::iter::Map<core::slice::Iter<'a, (K, V)>, fn(&'a (K, V)) -> (&'a K, &'a V)>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.iter().map(|(k, v)| (k, v))
        }
    }
    impl<'a, K, V, const S: bool> IntoIterator for &'a mut VecMap<K, V, S> {
        type Item = (&'a K, &'a mut V);
        type IntoIter = core::iter::Map<
            core::slice::IterMut<'a, (K, V)>,
            fn(&'a mut (K, V)) -> (&'a K, &'a mut V),
        >;
        fn into_iter(self) -> Self::IntoIter {
            self.0.iter_mut().map(|(k, v)| (&*k, v))
        }
    }
    impl<K: Eq + Borrow<Q>, Q: Eq + ?Sized, V, const S: bool> core::ops::Index<&Q> for VecMap<K, V, S> {
        type Output = V;
        fn index(&self, k: &Q) -> &V {
            self.get(k).expect("no such key")
        }
    }

    impl<K, const S: bool> VecSet<K, S> {
        pub fn new() -> Self {
            VecSet(VecMap::default())
        }
        pub fn len(&self) -> usize {
            self.0.len()
        }
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
        pub fn clear(&mut self) {
            self.0.clear()
        }
        pub fn iter(&self) -> impl DoubleEndedIterator<Item = &K> + ExactSizeIterator {
            self.0.keys()
        }
        pub fn retain(&mut self, mut f: impl FnMut(&K) -> bool) {
            self.0.retain(|k, _| f(k))
        }
    }
    impl<K: Eq, const S: bool> VecSet<K, S> {
        pub fn contains<Q: Eq + ?Sized>(&self, k: &Q) -> bool
        where
            K: Borrow<Q>,
        {
            self.0.contains_key(k)
        }
        pub fn remove<Q: Eq + ?Sized>(&mut self, k: &Q) -> bool
        where
            K: Borrow<Q>,
        {
            self.0.remove(k).is_some()
        }
    }
    impl<K: Eq, const S: bool> VecSet<K, S>
    where
        VecMap<K, (), S>: Place<K>,
    {
        /// Adds `k`, returning whether it was new.
        pub fn insert(&mut self, k: K) -> bool {
            self.0.insert(k, ()).is_none()
        }
    }
    impl<K: Eq, const S: bool> PartialEq for VecSet<K, S> {
        fn eq(&self, o: &Self) -> bool {
            self.0 == o.0
        }
    }
    impl<K: Eq, const S: bool> Eq for VecSet<K, S> {}

    impl<K: fmt::Debug, const S: bool> fmt::Debug for VecSet<K, S> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_set().entries(self.iter()).finish()
        }
    }
    impl<K: Eq, const S: bool> Extend<K> for VecSet<K, S>
    where
        VecMap<K, (), S>: Place<K>,
    {
        fn extend<I: IntoIterator<Item = K>>(&mut self, it: I) {
            self.0.extend(it.into_iter().map(|k| (k, ())))
        }
    }
    impl<K: Eq, const S: bool> FromIterator<K> for VecSet<K, S>
    where
        VecMap<K, (), S>: Place<K>,
    {
        fn from_iter<I: IntoIterator<Item = K>>(it: I) -> Self {
            VecSet(it.into_iter().map(|k| (k, ())).collect())
        }
    }
    impl<K: Eq, const N: usize, const S: bool> From<[K; N]> for VecSet<K, S>
    where
        VecMap<K, (), S>: Place<K>,
    {
        fn from(a: [K; N]) -> Self {
            a.into_iter().collect()
        }
    }
    impl<K, const S: bool> IntoIterator for VecSet<K, S> {
        type Item = K;
        type IntoIter = core::iter::Map<alloc::vec::IntoIter<(K, ())>, fn((K, ())) -> K>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter().map(|(k, _)| k)
        }
    }
    impl<'a, K, const S: bool> IntoIterator for &'a VecSet<K, S> {
        type Item = &'a K;
        type IntoIter = core::iter::Map<core::slice::Iter<'a, (K, ())>, fn(&'a (K, ())) -> &'a K>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.0.iter().map(|(k, _)| k)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn insertion_order_kept_and_replaced_in_place() {
            let mut m: VecMap<u32, &str> = VecMap::new();
            m.insert(3, "c");
            m.insert(1, "a");
            assert_eq!(m.insert(3, "C"), Some("c"));
            *m.entry(2).or_default() = "b";
            assert_eq!(
                m.iter().collect::<Vec<_>>(),
                [(&3, &"C"), (&1, &"a"), (&2, &"b")]
            );
            assert_eq!(m.remove(&3), Some("C"));
            assert_eq!(m.keys().copied().collect::<Vec<_>>(), [1, 2]);
        }

        #[test]
        fn sorted_and_unordered_equality() {
            let mut s: VecSet<u32, true> = VecSet::new();
            for k in [5, 1, 3, 1] {
                s.insert(k);
            }
            assert_eq!(s.iter().copied().collect::<Vec<_>>(), [1, 3, 5]);
            let a: VecMap<u32, u32> = [(1, 1), (2, 2)].into();
            let b: VecMap<u32, u32> = [(2, 2), (1, 1)].into();
            assert_eq!(a, b);
            let mut v = [3, 1, 2, 1];
            super::super::sort(&mut v);
            assert_eq!(v, [1, 1, 2, 3]);
        }
    }
}
