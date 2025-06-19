package it.sephiroth.android.library.xtooltip;

/* loaded from: classes3.dex */
public final class h implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ i b;

    public /* synthetic */ h(i iVar, int i) {
        this.a = i;
        this.b = iVar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.y = true;
                break;
            default:
                this.b.c();
                break;
        }
    }
}
