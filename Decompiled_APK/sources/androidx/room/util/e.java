package androidx.room.util;

import java.util.AbstractSet;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e {
    public final String a;
    public final Object b;
    public final AbstractSet c;
    public final AbstractSet d;

    public e(String name, Map columns, AbstractSet foreignKeys, AbstractSet abstractSet) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(columns, "columns");
        Intrinsics.checkNotNullParameter(foreignKeys, "foreignKeys");
        this.a = name;
        this.b = columns;
        this.c = foreignKeys;
        this.d = abstractSet;
    }

    /* JADX WARN: Code restructure failed: missing block: B:64:0x01f1, code lost:
    
        r9 = kotlin.collections.Z.a(r10);
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x01f5, code lost:
    
        r3.close();
     */
    /* JADX WARN: Finally extract failed */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final androidx.room.util.e a(androidx.sqlite.db.framework.b r26, java.lang.String r27) {
        /*
            Method dump skipped, instructions count: 532
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.room.util.e.a(androidx.sqlite.db.framework.b, java.lang.String):androidx.room.util.e");
    }

    public final boolean equals(Object obj) {
        AbstractSet abstractSet;
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        if (!this.a.equals(eVar.a) || !this.b.equals(eVar.b) || !Intrinsics.b(this.c, eVar.c)) {
            return false;
        }
        AbstractSet abstractSet2 = this.d;
        if (abstractSet2 == null || (abstractSet = eVar.d) == null) {
            return true;
        }
        return abstractSet2.equals(abstractSet);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "TableInfo{name='" + this.a + "', columns=" + this.b + ", foreignKeys=" + this.c + ", indices=" + this.d + '}';
    }
}
