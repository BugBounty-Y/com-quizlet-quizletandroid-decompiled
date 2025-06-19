package androidx.core.view;

import android.text.TextUtils;
import android.view.View;

/* loaded from: classes.dex */
public final class G extends I {
    public final /* synthetic */ int e;

    public G(int i, Class cls, int i2, int i3, int i4) {
        this.e = i4;
        this.a = i;
        this.d = cls;
        this.c = i2;
        this.b = i3;
    }

    @Override // androidx.core.view.I
    public final Object d(View view) {
        switch (this.e) {
            case 0:
                return Boolean.valueOf(P.c(view));
            case 1:
                return P.a(view);
            case 2:
                return S.b(view);
            default:
                return Boolean.valueOf(P.b(view));
        }
    }

    @Override // androidx.core.view.I
    public final void e(View view, Object obj) {
        switch (this.e) {
            case 0:
                P.f(view, ((Boolean) obj).booleanValue());
                break;
            case 1:
                P.e(view, (CharSequence) obj);
                break;
            case 2:
                S.d(view, (CharSequence) obj);
                break;
            default:
                P.d(view, ((Boolean) obj).booleanValue());
                break;
        }
    }

    @Override // androidx.core.view.I
    public final boolean h(Object obj, Object obj2) {
        switch (this.e) {
            case 0:
                Boolean bool = (Boolean) obj;
                Boolean bool2 = (Boolean) obj2;
                return !((bool != null && bool.booleanValue()) == (bool2 != null && bool2.booleanValue()));
            case 1:
                return !TextUtils.equals((CharSequence) obj, (CharSequence) obj2);
            case 2:
                return !TextUtils.equals((CharSequence) obj, (CharSequence) obj2);
            default:
                Boolean bool3 = (Boolean) obj;
                Boolean bool4 = (Boolean) obj2;
                return !((bool3 != null && bool3.booleanValue()) == (bool4 != null && bool4.booleanValue()));
        }
    }
}
