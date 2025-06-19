package androidx.appcompat.widget;

/* loaded from: classes.dex */
public final class C0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ G0 b;

    public /* synthetic */ C0(G0 g0, int i) {
        this.a = i;
        this.b = g0;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C0113u0 c0113u0 = this.b.c;
                if (c0113u0 != null) {
                    c0113u0.setListSelectionHidden(true);
                    c0113u0.requestLayout();
                    break;
                }
                break;
            default:
                G0 g0 = this.b;
                C0113u0 c0113u02 = g0.c;
                if (c0113u02 != null && c0113u02.isAttachedToWindow() && g0.c.getCount() > g0.c.getChildCount() && g0.c.getChildCount() <= g0.m) {
                    g0.z.setInputMethodMode(2);
                    g0.f();
                    break;
                }
                break;
        }
    }
}
