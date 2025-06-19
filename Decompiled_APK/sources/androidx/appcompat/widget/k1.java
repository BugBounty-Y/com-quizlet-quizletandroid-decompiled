package androidx.appcompat.widget;

import android.graphics.PointF;
import android.graphics.Rect;
import android.util.Property;
import android.view.View;
import androidx.transition.C1401d;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class k1 extends Property {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ k1(int i, Class cls, String str) {
        super(cls, str);
        this.a = i;
    }

    @Override // android.util.Property
    public final Object get(Object obj) {
        switch (this.a) {
            case 0:
                return Float.valueOf(((SwitchCompat) obj).z);
            case 1:
                return null;
            case 2:
                return null;
            case 3:
                return null;
            case 4:
                return null;
            case 5:
                return null;
            case 6:
                return Float.valueOf(androidx.transition.L.a.a((View) obj));
            case 7:
                return ((View) obj).getClipBounds();
            case 8:
                return Float.valueOf(((View) obj).getLayoutParams().width);
            case 9:
                return Float.valueOf(((View) obj).getLayoutParams().height);
            case 10:
                WeakHashMap weakHashMap = androidx.core.view.V.a;
                return Float.valueOf(((View) obj).getPaddingStart());
            default:
                WeakHashMap weakHashMap2 = androidx.core.view.V.a;
                return Float.valueOf(((View) obj).getPaddingEnd());
        }
    }

    @Override // android.util.Property
    public final void set(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((SwitchCompat) obj).setThumbPosition(((Float) obj2).floatValue());
                break;
            case 1:
                C1401d c1401d = (C1401d) obj;
                PointF pointF = (PointF) obj2;
                c1401d.getClass();
                c1401d.a = Math.round(pointF.x);
                int iRound = Math.round(pointF.y);
                c1401d.b = iRound;
                int i = c1401d.f + 1;
                c1401d.f = i;
                if (i == c1401d.g) {
                    androidx.transition.L.a(c1401d.e, c1401d.a, iRound, c1401d.c, c1401d.d);
                    c1401d.f = 0;
                    c1401d.g = 0;
                    break;
                }
                break;
            case 2:
                C1401d c1401d2 = (C1401d) obj;
                PointF pointF2 = (PointF) obj2;
                c1401d2.getClass();
                c1401d2.c = Math.round(pointF2.x);
                int iRound2 = Math.round(pointF2.y);
                c1401d2.d = iRound2;
                int i2 = c1401d2.g + 1;
                c1401d2.g = i2;
                if (c1401d2.f == i2) {
                    androidx.transition.L.a(c1401d2.e, c1401d2.a, c1401d2.b, c1401d2.c, iRound2);
                    c1401d2.f = 0;
                    c1401d2.g = 0;
                    break;
                }
                break;
            case 3:
                View view = (View) obj;
                PointF pointF3 = (PointF) obj2;
                androidx.transition.L.a(view, view.getLeft(), view.getTop(), Math.round(pointF3.x), Math.round(pointF3.y));
                break;
            case 4:
                View view2 = (View) obj;
                PointF pointF4 = (PointF) obj2;
                androidx.transition.L.a(view2, Math.round(pointF4.x), Math.round(pointF4.y), view2.getRight(), view2.getBottom());
                break;
            case 5:
                View view3 = (View) obj;
                PointF pointF5 = (PointF) obj2;
                int iRound3 = Math.round(pointF5.x);
                int iRound4 = Math.round(pointF5.y);
                androidx.transition.L.a(view3, iRound3, iRound4, view3.getWidth() + iRound3, view3.getHeight() + iRound4);
                break;
            case 6:
                float fFloatValue = ((Float) obj2).floatValue();
                androidx.transition.L.a.c((View) obj, fFloatValue);
                break;
            case 7:
                ((View) obj).setClipBounds((Rect) obj2);
                break;
            case 8:
                View view4 = (View) obj;
                view4.getLayoutParams().width = ((Float) obj2).intValue();
                view4.requestLayout();
                break;
            case 9:
                View view5 = (View) obj;
                view5.getLayoutParams().height = ((Float) obj2).intValue();
                view5.requestLayout();
                break;
            case 10:
                View view6 = (View) obj;
                int iIntValue = ((Float) obj2).intValue();
                int paddingTop = view6.getPaddingTop();
                WeakHashMap weakHashMap = androidx.core.view.V.a;
                view6.setPaddingRelative(iIntValue, paddingTop, view6.getPaddingEnd(), view6.getPaddingBottom());
                break;
            default:
                View view7 = (View) obj;
                WeakHashMap weakHashMap2 = androidx.core.view.V.a;
                view7.setPaddingRelative(view7.getPaddingStart(), view7.getPaddingTop(), ((Float) obj2).intValue(), view7.getPaddingBottom());
                break;
        }
    }
}
