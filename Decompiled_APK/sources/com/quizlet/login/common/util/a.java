package com.quizlet.login.common.util;

import android.content.Context;
import android.widget.Toast;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ServerProvidedError;
import com.quizlet.api.util.ApiErrorResolver;
import com.quizlet.quizletandroid.R;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public static final a a = new a();

    public static boolean a(Context context, ApiThreeWrapper apiThreeWrapper, Throwable th, String str) {
        ServerProvidedError error;
        List responses;
        ApiResponse apiResponse;
        String string;
        Intrinsics.checkNotNullParameter(context, "context");
        ServerProvidedError error2 = null;
        com.quizlet.baseui.base.b bVar = context instanceof com.quizlet.baseui.base.b ? (com.quizlet.baseui.base.b) context : null;
        if (bVar != null) {
            bVar.I(false);
        }
        if (apiThreeWrapper == null || (error = apiThreeWrapper.getError()) == null) {
            if (apiThreeWrapper != null && (responses = apiThreeWrapper.getResponses()) != null && (apiResponse = (ApiResponse) CollectionsKt.firstOrNull(responses)) != null) {
                error2 = apiResponse.getError();
            }
            error = error2;
        }
        if (th != null || apiThreeWrapper == null) {
            if (th != null) {
                th.printStackTrace();
            }
            string = context.getString(R.string.unable_to_reach_quizlet_msg);
        } else {
            string = error != null ? ApiErrorResolver.a(context, error) : str;
        }
        if (string != null) {
            Toast.makeText(context, string, 1).show();
        }
        return Intrinsics.b(string, str);
    }
}
