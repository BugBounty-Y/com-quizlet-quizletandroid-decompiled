package androidx.appcompat.widget;

/* renamed from: androidx.appcompat.widget.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C0074b0 extends com.google.firebase.platforminfo.c {
    public final /* synthetic */ AppCompatTextView c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0074b0(AppCompatTextView appCompatTextView) {
        super(appCompatTextView);
        this.c = appCompatTextView;
    }

    @Override // com.google.firebase.platforminfo.c, androidx.appcompat.widget.InterfaceC0071a0
    public final void b(int i) {
        super/*android.widget.TextView*/.setLastBaselineToBottomHeight(i);
    }

    @Override // com.google.firebase.platforminfo.c, androidx.appcompat.widget.InterfaceC0071a0
    public final void c(int i) {
        super/*android.widget.TextView*/.setFirstBaselineToTopHeight(i);
    }
}
