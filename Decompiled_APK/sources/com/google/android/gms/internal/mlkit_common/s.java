package com.google.android.gms.internal.mlkit_common;

import android.content.Context;
import android.os.Build;
import androidx.activity.AbstractC0029a;
import com.quizlet.data.exceptions.practicetests.PracticeTestsException;
import com.quizlet.generated.enums.EnumC4518s0;
import java.util.Objects;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.I;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class s {
    public static r a;
    public static final /* synthetic */ int b = 0;

    public static final void a(I i) throws PracticeTestsException {
        Intrinsics.checkNotNullParameter(i, "<this>");
        if (!Intrinsics.b(c(i), EnumC4518s0.CONSUMPTION_METER_REACHED.a())) {
            throw new PracticeTestsException(null);
        }
    }

    public static Context b(Context context) {
        int iG;
        Context applicationContext = context.getApplicationContext();
        int i = Build.VERSION.SDK_INT;
        if (i >= 34 && (iG = AbstractC0029a.g(context)) != AbstractC0029a.g(applicationContext)) {
            applicationContext = AbstractC0029a.a(applicationContext, iG);
        }
        if (i >= 30) {
            String strC = androidx.camera.core.impl.utils.d.c(context);
            if (!Objects.equals(strC, androidx.camera.core.impl.utils.d.c(applicationContext))) {
                return androidx.camera.core.impl.utils.d.a(applicationContext, strC);
            }
        }
        return applicationContext;
    }

    public static final String c(I i) throws JSONException {
        Intrinsics.checkNotNullParameter(i, "<this>");
        String string = new JSONObject(i.f()).getJSONObject("error").getString("identifier");
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        return string;
    }
}
