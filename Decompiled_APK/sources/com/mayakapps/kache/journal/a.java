package com.mayakapps.kache.journal;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final LinkedHashMap a;
    public final LinkedHashSet b;
    public final int c;

    public a(LinkedHashMap cleanEntries, LinkedHashSet dirtyEntryKeys, int i) {
        Intrinsics.checkNotNullParameter(cleanEntries, "cleanEntries");
        Intrinsics.checkNotNullParameter(dirtyEntryKeys, "dirtyEntryKeys");
        this.a = cleanEntries;
        this.b = dirtyEntryKeys;
        this.c = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a.equals(aVar.a) && this.b.equals(aVar.b) && this.c == aVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("JournalData(cleanEntries=");
        sb.append(this.a);
        sb.append(", dirtyEntryKeys=");
        sb.append(this.b);
        sb.append(", redundantEntriesCount=");
        return android.support.v4.media.session.a.q(sb, this.c, ')');
    }
}
