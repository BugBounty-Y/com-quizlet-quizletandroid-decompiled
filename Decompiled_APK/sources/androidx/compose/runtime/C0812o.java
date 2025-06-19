package androidx.compose.runtime;

/* renamed from: androidx.compose.runtime.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0812o {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ C0812o(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public final void a() {
        switch (this.a) {
            case 0:
                C0814p c0814p = (C0814p) this.b;
                c0814p.z--;
                break;
            default:
                androidx.compose.runtime.snapshots.u uVar = (androidx.compose.runtime.snapshots.u) this.b;
                uVar.j--;
                break;
        }
    }

    public final void b() {
        switch (this.a) {
            case 0:
                ((C0814p) this.b).z++;
                break;
            default:
                ((androidx.compose.runtime.snapshots.u) this.b).j++;
                break;
        }
    }
}
