package androidx.camera.core;

/* loaded from: classes.dex */
public final /* synthetic */ class N implements InterfaceC0198v {
    public final /* synthetic */ int a;
    public final /* synthetic */ O b;

    public /* synthetic */ N(O o, O o2, int i) {
        this.a = i;
        this.b = o2;
    }

    @Override // androidx.camera.core.InterfaceC0198v
    public final void a(AbstractC0199w abstractC0199w) throws Exception {
        O o = this.b;
        switch (this.a) {
            case 0:
                int i = ImageProcessingUtil.a;
                o.close();
                break;
            default:
                int i2 = ImageProcessingUtil.a;
                if (o != null) {
                    o.close();
                    break;
                }
                break;
        }
    }
}
