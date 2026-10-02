// SPDX-License-Identifier: AGPL-3.0-or-later
package io.github.miam1ku.mibandoplusbridge.data;

import java.util.ArrayList;
import java.util.List;

/** Decides which sleep file owns an interval. The newest file wins; an empty analysis does not. */
public final class SleepStageAlign {
    private SleepStageAlign() {}

    public record Interval(long startMs, long endMs) {
        public boolean overlaps(long start, long end) {
            return start < endMs && end > startMs;
        }
    }

    /** Intervals in this file that a newer file has not already taken. */
    public static List<Interval> claim(List<Interval> fileIntervals, List<Interval> newer) {
        List<Interval> owned = new ArrayList<>();
        if (fileIntervals == null) return owned;
        OverlapIndex index = OverlapIndex.of(newer);
        for (Interval interval : fileIntervals) {
            if (interval == null || interval.endMs() <= interval.startMs()) continue;
            if (index.overlaps(interval.startMs(), interval.endMs())) continue;
            owned.add(interval);
        }
        return owned;
    }

    /** An owned interval with no stage stays free so an older file can keep its chart. */
    public static List<Interval> withStages(List<Interval> owned, List<Interval> stages) {
        List<Interval> covered = new ArrayList<>();
        if (owned == null) return covered;
        OverlapIndex index = OverlapIndex.of(stages);
        for (Interval interval : owned) {
            if (interval != null && index.overlaps(interval.startMs(), interval.endMs())) covered.add(interval);
        }
        return covered;
    }

    public static boolean overlapsAny(long startMs, long endMs, List<Interval> others) {
        if (others == null || endMs <= startMs) return false;
        for (Interval other : others) {
            if (other != null && other.overlaps(startMs, endMs)) return true;
        }
        return false;
    }

    /**
     * Immutable overlap index. Building is O(m log m); each query is O(log m).
     * Prefix maximum ends keep nested/overlapping intervals correct without merging.
     */
    private static final class OverlapIndex {
        private static final OverlapIndex EMPTY = new OverlapIndex(new long[0], new long[0]);
        private final long[] starts;
        private final long[] maxEnds;

        private OverlapIndex(long[] starts, long[] maxEnds) {
            this.starts = starts;
            this.maxEnds = maxEnds;
        }

        static OverlapIndex of(List<Interval> intervals) {
            if (intervals == null || intervals.isEmpty()) return EMPTY;
            List<Interval> valid = new ArrayList<>(intervals.size());
            for (Interval interval : intervals) {
                if (interval != null && interval.endMs() > interval.startMs()) valid.add(interval);
            }
            if (valid.isEmpty()) return EMPTY;
            valid.sort(java.util.Comparator.comparingLong(Interval::startMs));
            long[] starts = new long[valid.size()];
            long[] maxEnds = new long[valid.size()];
            long max = Long.MIN_VALUE;
            for (int i = 0; i < valid.size(); i++) {
                Interval interval = valid.get(i);
                starts[i] = interval.startMs();
                max = Math.max(max, interval.endMs());
                maxEnds[i] = max;
            }
            return new OverlapIndex(starts, maxEnds);
        }

        boolean overlaps(long startMs, long endMs) {
            if (endMs <= startMs || starts.length == 0) return false;
            int low = 0;
            int high = starts.length;
            while (low < high) {
                int mid = (low + high) >>> 1;
                if (starts[mid] < endMs) low = mid + 1;
                else high = mid;
            }
            int lastStartBeforeEnd = low - 1;
            return lastStartBeforeEnd >= 0 && maxEnds[lastStartBeforeEnd] > startMs;
        }
    }
}
