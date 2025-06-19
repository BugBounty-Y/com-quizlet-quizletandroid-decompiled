package androidx.appcompat.view;

import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.os.Bundle;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.RootActivity;

/* loaded from: classes.dex */
public final class a {
    public Context a;

    public static a a(Context context) {
        a aVar = new a();
        aVar.a = context;
        return aVar;
    }

    public Intent b() {
        Intent intent = new Intent(this.a, (Class<?>) RootActivity.class);
        intent.addFlags(268435456);
        intent.setAction("android.intent.action.MAIN");
        intent.addCategory("android.intent.category.LAUNCHER");
        Bundle bundle = new Bundle();
        bundle.putString("quizletWidgetUrlKey", "androidwidget://quizlet.com");
        intent.putExtras(bundle);
        return intent;
    }

    public Intent c(long j) {
        Intent intentB = com.quizlet.features.setpage.e.b(SetPageActivity.h1, this.a, j, null, null, null, null, false, null, 252);
        intentB.addFlags(268435456);
        Bundle bundle = new Bundle();
        bundle.putString("quizletWidgetUrlKey", "androidwidget://quizlet.com/" + j);
        intentB.putExtras(bundle);
        return intentB;
    }

    public int d() {
        Configuration configuration = this.a.getResources().getConfiguration();
        int i = configuration.screenWidthDp;
        int i2 = configuration.screenHeightDp;
        if (configuration.smallestScreenWidthDp > 600 || i > 600) {
            return 5;
        }
        if (i > 960 && i2 > 720) {
            return 5;
        }
        if (i > 720 && i2 > 960) {
            return 5;
        }
        if (i >= 500) {
            return 4;
        }
        if (i > 640 && i2 > 480) {
            return 4;
        }
        if (i <= 480 || i2 <= 640) {
            return i >= 360 ? 3 : 2;
        }
        return 4;
    }

    public int e() {
        int[] iArr = androidx.appcompat.a.a;
        Context context = this.a;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(null, iArr, R.attr.actionBarStyle, 0);
        int layoutDimension = typedArrayObtainStyledAttributes.getLayoutDimension(13, 0);
        Resources resources = context.getResources();
        if (!this.a.getResources().getBoolean(R.bool.abc_action_bar_embed_tabs)) {
            layoutDimension = Math.min(layoutDimension, resources.getDimensionPixelSize(R.dimen.abc_action_bar_stacked_max_height));
        }
        typedArrayObtainStyledAttributes.recycle();
        return layoutDimension;
    }
}
