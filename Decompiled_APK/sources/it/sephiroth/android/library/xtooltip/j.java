package it.sephiroth.android.library.xtooltip;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import androidx.appcompat.widget.AppCompatImageView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class j extends AppCompatImageView {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(@NotNull Context context) throws Resources.NotFoundException {
        super(context, null, R.style.ToolTipOverlayDefaultStyle);
        Intrinsics.f(context, "context");
        setImageDrawable(new l(context, R.style.ToolTipLayoutDefaultStyle));
        TypedArray typedArrayObtainStyledAttributes = context.getTheme().obtainStyledAttributes(R.style.ToolTipLayoutDefaultStyle, b.b);
        typedArrayObtainStyledAttributes.getDimensionPixelSize(0, 0);
        typedArrayObtainStyledAttributes.recycle();
    }
}
