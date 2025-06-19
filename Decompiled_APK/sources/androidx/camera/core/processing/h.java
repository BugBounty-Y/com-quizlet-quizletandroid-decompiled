package androidx.camera.core.processing;

import com.braze.ui.contentcards.adapters.ContentCardAdapter;

/* loaded from: classes.dex */
public final /* synthetic */ class h implements Runnable {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;

    public /* synthetic */ h(int i, int i2, ContentCardAdapter contentCardAdapter) {
        this.b = i;
        this.c = i2;
        this.d = contentCardAdapter;
    }

    @Override // java.lang.Runnable
    public final void run() {
        boolean z;
        switch (this.a) {
            case 0:
                k kVar = (k) this.d;
                int i = kVar.i;
                int i2 = this.b;
                boolean z2 = true;
                if (i != i2) {
                    kVar.i = i2;
                    z = true;
                } else {
                    z = false;
                }
                int i3 = kVar.h;
                int i4 = this.c;
                if (i3 != i4) {
                    kVar.h = i4;
                } else {
                    z2 = z;
                }
                if (z2) {
                    kVar.e();
                    break;
                }
                break;
            default:
                ContentCardAdapter.markOnScreenCardsAsRead$lambda$6(this.b, this.c, (ContentCardAdapter) this.d);
                break;
        }
    }

    public /* synthetic */ h(k kVar, int i, int i2) {
        this.d = kVar;
        this.b = i;
        this.c = i2;
    }
}
