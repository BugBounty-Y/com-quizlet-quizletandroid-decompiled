package androidx.compose.material3;

import android.graphics.Outline;
import android.view.View;
import android.view.ViewOutlineProvider;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.i2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0634i2 extends ViewOutlineProvider {
    public final /* synthetic */ int a;

    public /* synthetic */ C0634i2(int i) {
        this.a = i;
    }

    @Override // android.view.ViewOutlineProvider
    public final void getOutline(View view, Outline outline) {
        Outline outline2;
        switch (this.a) {
            case 0:
                outline.setRect(0, 0, view.getWidth(), view.getHeight());
                outline.setAlpha(DefinitionKt.NO_Float_VALUE);
                break;
            case 1:
                if ((view instanceof androidx.compose.ui.graphics.layer.o) && (outline2 = ((androidx.compose.ui.graphics.layer.o) view).e) != null) {
                    outline.set(outline2);
                    break;
                }
                break;
            case 2:
                Intrinsics.e(view, "null cannot be cast to non-null type androidx.compose.ui.platform.ViewLayer");
                Outline outlineB = ((androidx.compose.ui.platform.a1) view).e.b();
                Intrinsics.d(outlineB);
                outline.set(outlineB);
                break;
            case 3:
                outline.setRect(0, 0, view.getWidth(), view.getHeight());
                outline.setAlpha(DefinitionKt.NO_Float_VALUE);
                break;
            default:
                outline.setRect(0, 0, view.getWidth(), view.getHeight());
                outline.setAlpha(DefinitionKt.NO_Float_VALUE);
                break;
        }
    }
}
