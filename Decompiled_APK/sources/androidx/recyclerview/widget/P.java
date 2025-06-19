package androidx.recyclerview.widget;

import android.view.View;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.List;

/* loaded from: classes.dex */
public final class P {
    public boolean a;
    public int b;
    public int c;
    public int d;
    public int e;
    public int f;
    public int g;
    public int h;
    public int i;
    public int j;
    public List k;
    public boolean l;

    public final void a(View view) {
        int layoutPosition;
        int size = this.k.size();
        View view2 = null;
        int i = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        for (int i2 = 0; i2 < size; i2++) {
            View view3 = ((F0) this.k.get(i2)).itemView;
            C1383o0 c1383o0 = (C1383o0) view3.getLayoutParams();
            if (view3 != view && !c1383o0.a.isRemoved() && (layoutPosition = (c1383o0.a.getLayoutPosition() - this.d) * this.e) >= 0 && layoutPosition < i) {
                view2 = view3;
                if (layoutPosition == 0) {
                    break;
                } else {
                    i = layoutPosition;
                }
            }
        }
        if (view2 == null) {
            this.d = -1;
        } else {
            this.d = ((C1383o0) view2.getLayoutParams()).a.getLayoutPosition();
        }
    }

    public final View b(v0 v0Var) {
        List list = this.k;
        if (list == null) {
            View view = v0Var.k(this.d, Long.MAX_VALUE).itemView;
            this.d += this.e;
            return view;
        }
        int size = list.size();
        for (int i = 0; i < size; i++) {
            View view2 = ((F0) this.k.get(i)).itemView;
            C1383o0 c1383o0 = (C1383o0) view2.getLayoutParams();
            if (!c1383o0.a.isRemoved() && this.d == c1383o0.a.getLayoutPosition()) {
                a(view2);
                return view2;
            }
        }
        return null;
    }
}
