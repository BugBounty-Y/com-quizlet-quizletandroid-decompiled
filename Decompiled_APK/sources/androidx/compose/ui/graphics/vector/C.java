package androidx.compose.ui.graphics.vector;

/* loaded from: classes.dex */
public abstract class C {
    public final boolean a;
    public final boolean b;

    public C(int i) {
        boolean z = (i & 1) == 0;
        boolean z2 = (i & 2) == 0;
        this.a = z;
        this.b = z2;
    }
}
