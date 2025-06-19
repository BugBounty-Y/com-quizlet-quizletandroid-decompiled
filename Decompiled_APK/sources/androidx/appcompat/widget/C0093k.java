package androidx.appcompat.widget;

import android.content.Context;
import android.graphics.drawable.Drawable;
import androidx.appcompat.view.menu.C0065b;
import com.quizlet.quizletandroid.R;

/* renamed from: androidx.appcompat.widget.k, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0093k extends AppCompatImageView implements InterfaceC0097m {
    public final /* synthetic */ C0095l d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0093k(C0095l c0095l, Context context) {
        super(context, null, R.attr.actionOverflowButtonStyle);
        this.d = c0095l;
        setClickable(true);
        setFocusable(true);
        setVisibility(0);
        setEnabled(true);
        y1.a(this, getContentDescription());
        setOnTouchListener(new C0065b(this, this));
    }

    @Override // androidx.appcompat.widget.InterfaceC0097m
    public final boolean a() {
        return false;
    }

    @Override // androidx.appcompat.widget.InterfaceC0097m
    public final boolean b() {
        return false;
    }

    @Override // android.view.View
    public final boolean performClick() {
        if (super.performClick()) {
            return true;
        }
        playSoundEffect(0);
        this.d.l();
        return true;
    }

    @Override // android.widget.ImageView
    public final boolean setFrame(int i, int i2, int i3, int i4) {
        boolean frame = super.setFrame(i, i2, i3, i4);
        Drawable drawable = getDrawable();
        Drawable background = getBackground();
        if (drawable != null && background != null) {
            int width = getWidth();
            int height = getHeight();
            int iMax = Math.max(width, height) / 2;
            int paddingLeft = (width + (getPaddingLeft() - getPaddingRight())) / 2;
            int paddingTop = (height + (getPaddingTop() - getPaddingBottom())) / 2;
            background.setHotspotBounds(paddingLeft - iMax, paddingTop - iMax, paddingLeft + iMax, paddingTop + iMax);
        }
        return frame;
    }
}
