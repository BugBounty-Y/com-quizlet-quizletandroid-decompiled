package androidx.appcompat.widget;

/* loaded from: classes.dex */
public final /* synthetic */ class q1 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Toolbar b;

    public /* synthetic */ q1(Toolbar toolbar, int i) {
        this.a = i;
        this.b = toolbar;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                s1 s1Var = this.b.M;
                androidx.appcompat.view.menu.p pVar = s1Var == null ? null : s1Var.b;
                if (pVar != null) {
                    pVar.collapseActionView();
                    break;
                }
                break;
            default:
                this.b.n();
                break;
        }
    }
}
