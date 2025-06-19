package androidx.room;

import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class k {
    public final String[] a;

    public k(String[] tables) {
        Intrinsics.checkNotNullParameter(tables, "tables");
        this.a = tables;
    }

    public abstract void a(Set set);
}
