package androidx.appcompat.widget;

/* loaded from: classes.dex */
public final class I extends AbstractViewOnTouchListenerC0119x0 {
    public final /* synthetic */ O j;
    public final /* synthetic */ AppCompatSpinner k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(AppCompatSpinner appCompatSpinner, AppCompatSpinner appCompatSpinner2, O o) {
        super(appCompatSpinner2);
        this.k = appCompatSpinner;
        this.j = o;
    }

    @Override // androidx.appcompat.widget.AbstractViewOnTouchListenerC0119x0
    public final androidx.appcompat.view.menu.D b() {
        return this.j;
    }

    @Override // androidx.appcompat.widget.AbstractViewOnTouchListenerC0119x0
    public final boolean c() {
        AppCompatSpinner appCompatSpinner = this.k;
        if (appCompatSpinner.getInternalPopup().a()) {
            return true;
        }
        appCompatSpinner.f.m(appCompatSpinner.getTextDirection(), appCompatSpinner.getTextAlignment());
        return true;
    }
}
