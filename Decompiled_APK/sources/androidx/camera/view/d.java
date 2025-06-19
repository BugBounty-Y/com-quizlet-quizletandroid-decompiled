package androidx.camera.view;

import android.view.View;
import androidx.compose.ui.text.input.C;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.material.carousel.CarouselLayoutManager;

/* loaded from: classes.dex */
public final /* synthetic */ class d implements View.OnLayoutChangeListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.view.View.OnLayoutChangeListener
    public final void onLayoutChange(View view, int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                int i9 = PreviewView.m;
                PreviewView previewView = (PreviewView) obj;
                if (i3 - i != i7 - i5 || i4 - i2 != i8 - i6) {
                    previewView.a();
                    S.d();
                    previewView.getViewPort();
                    break;
                }
                break;
            default:
                CarouselLayoutManager carouselLayoutManager = (CarouselLayoutManager) obj;
                if (i != i5 || i2 != i6 || i3 != i7 || i4 != i8) {
                    view.post(new C(carouselLayoutManager, 23));
                    break;
                }
        }
    }
}
