package androidx.constraintlayout.motion.utils;

import android.view.View;

/* loaded from: classes.dex */
public final class l extends p {
    public final /* synthetic */ int j;

    public /* synthetic */ l(int i) {
        this.j = i;
    }

    @Override // androidx.constraintlayout.motion.utils.p
    public final boolean c(float f, long j, View view, androidx.constraintlayout.core.motion.utils.e eVar) {
        switch (this.j) {
            case 0:
                view.setAlpha(b(f, j, view, eVar));
                break;
            case 1:
                view.setElevation(b(f, j, view, eVar));
                break;
            case 2:
                view.setRotation(b(f, j, view, eVar));
                break;
            case 3:
                view.setRotationX(b(f, j, view, eVar));
                break;
            case 4:
                view.setRotationY(b(f, j, view, eVar));
                break;
            case 5:
                view.setScaleX(b(f, j, view, eVar));
                break;
            case 6:
                view.setScaleY(b(f, j, view, eVar));
                break;
            case 7:
                view.setTranslationX(b(f, j, view, eVar));
                break;
            case 8:
                view.setTranslationY(b(f, j, view, eVar));
                break;
            default:
                view.setTranslationZ(b(f, j, view, eVar));
                break;
        }
        return this.g;
    }
}
