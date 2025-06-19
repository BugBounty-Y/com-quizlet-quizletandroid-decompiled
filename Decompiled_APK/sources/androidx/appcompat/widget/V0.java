package androidx.appcompat.widget;

/* loaded from: classes.dex */
public final class V0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ SearchView b;

    public /* synthetic */ V0(SearchView searchView, int i) {
        this.a = i;
        this.b = searchView;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.v();
                break;
            default:
                androidx.cursoradapter.widget.a aVar = this.b.d1;
                if (aVar instanceof j1) {
                    aVar.b(null);
                    break;
                }
                break;
        }
    }
}
