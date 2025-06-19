package androidx.navigation.compose;

import android.app.Activity;
import android.content.Context;
import android.content.res.Resources;
import com.braze.managers.C1507u;
import com.google.android.gms.internal.mlkit_vision_camera.P1;
import com.quizlet.diagrams.layoutmanager.DiagramCardLayoutManager;
import com.quizlet.quizletandroid.R;
import java.io.File;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class w implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Context b;

    public /* synthetic */ w(Context context, int i) {
        this.a = i;
        this.b = context;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() throws Resources.NotFoundException {
        Context context = this.b;
        switch (this.a) {
            case 0:
                return P1.b(context);
            case 1:
                return C1507u.a(context);
            case 2:
                int i = DiagramCardLayoutManager.I;
                return Integer.valueOf(Math.round((r0.widthPixels / 2.0f) - ((328 * context.getResources().getDisplayMetrics().density) / 2.0f)));
            case 3:
                Intrinsics.e(context, "null cannot be cast to non-null type android.app.Activity");
                ((Activity) context).finish();
                return Unit.a;
            case 4:
                Intrinsics.e(context, "null cannot be cast to non-null type android.app.Activity");
                ((Activity) context).finish();
                return Unit.a;
            case 5:
                return context.getSharedPreferences("STUDY_PREVIEW_PRFS", 0);
            case 6:
                return new File(context.getCacheDir(), "datastore/quizlet_global_data_cache.preferences_pb");
            case 7:
                try {
                    return androidx.core.content.res.k.a(context, R.font.glyphs_h156_regular);
                } catch (RuntimeException e) {
                    timber.log.c.a.e(new Exception("Error loading iconfont typeface", e));
                    androidx.compose.ui.text.font.m mVar = com.quizlet.ui.resources.designsystem.generated.a.a;
                    return androidx.core.content.res.k.a(context, com.quizlet.ui.resources.designsystem.generated.a.b);
                }
            case 8:
                return context.getSharedPreferences("SET_PREVIEW_PRFS", 0);
            case 9:
                String[] strArr = com.quizlet.generated.sharedconfig.c.d;
                String[] stringArray = context.getResources().getStringArray(R.array.all_languages_array);
                Intrinsics.checkNotNullExpressionValue(stringArray, "getStringArray(...)");
                return V.k(C4933y.U(strArr, stringArray));
            default:
                String[] strArr2 = com.quizlet.generated.sharedconfig.c.d;
                String[] stringArray2 = context.getResources().getStringArray(R.array.all_languages_all_caps_array);
                Intrinsics.checkNotNullExpressionValue(stringArray2, "getStringArray(...)");
                return V.k(C4933y.U(strArr2, stringArray2));
        }
    }
}
