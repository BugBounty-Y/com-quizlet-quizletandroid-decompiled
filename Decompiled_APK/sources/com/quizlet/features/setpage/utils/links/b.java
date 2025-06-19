package com.quizlet.features.setpage.utils.links;

import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.net.Uri;
import androidx.compose.animation.d0;
import com.quizlet.features.setpage.shareset.ShareIntentSender;
import com.quizlet.features.setpage.shareset.c;
import com.quizlet.quizletandroid.R;
import com.quizlet.utm.a;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final Context a;
    public final long b;
    public final String c;
    public final String d;
    public final a.C0023a e;
    public final String f;
    public final a g;

    public b(Context context, long j, String str, String studySetTitle, a.C0023a utmInfo, String str2, a aVar) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(studySetTitle, "studySetTitle");
        Intrinsics.checkNotNullParameter(utmInfo, "utmInfo");
        this.a = context;
        this.b = j;
        this.c = str;
        this.d = studySetTitle;
        this.e = utmInfo;
        this.f = str2;
        this.g = aVar;
    }

    public final Intent a(String str, Intent intent) {
        int i = ShareIntentSender.d;
        Intent intentCreateChooser = Intent.createChooser(intent, this.a.getResources().getString(R.string.share_set), c.a(this.a, str, Long.valueOf(this.b), 1, this.e, null));
        Intrinsics.checkNotNullExpressionValue(intentCreateChooser, "createChooser(...)");
        return intentCreateChooser;
    }

    public final Intent b(com.quizlet.features.infra.basestudy.data.models.shareset.a shareStatus) throws Resources.NotFoundException {
        Intent intentA;
        Intrinsics.checkNotNullParameter(shareStatus, "shareStatus");
        int iOrdinal = shareStatus.ordinal();
        if (iOrdinal == 0) {
            Pair pairC = c();
            intentA = a((String) pairC.b, (Intent) pairC.a);
        } else if (iOrdinal == 1) {
            Pair pairC2 = c();
            Intent intent = (Intent) pairC2.a;
            String str = (String) pairC2.b;
            intent.setAction("android.intent.action.SENDTO");
            intent.setData(Uri.parse("mailto:"));
            intentA = a(str, intent);
        } else if (iOrdinal == 2) {
            Pair pairC3 = c();
            Intent intent2 = (Intent) pairC3.a;
            String str2 = (String) pairC3.b;
            intent2.setPackage("com.whatsapp");
            intentA = a(str2, intent2);
        } else {
            if (iOrdinal != 3) {
                throw new NoWhenBranchMatchedException();
            }
            intentA = null;
        }
        if ((intentA != null ? intentA.resolveActivity(this.a.getPackageManager()) : null) == null) {
            return null;
        }
        return intentA;
    }

    public final Pair c() throws Resources.NotFoundException {
        String string;
        a.b bVarEncodeUriParams = com.quizlet.utm.a.encodeUriParams(this.e);
        long j = this.b;
        String strN = this.c;
        if (strN == null) {
            strN = d0.n(j, "https://quizlet.com/");
        }
        Uri.Builder builderAppendQueryParameter = Uri.parse(strN).buildUpon().appendQueryParameter("x", bVarEncodeUriParams.getUtmBlob()).appendQueryParameter("i", bVarEncodeUriParams.getUserId());
        String str = this.f;
        if (str != null) {
            builderAppendQueryParameter.path(String.valueOf(j));
            builderAppendQueryParameter.appendPath(str);
        }
        String string2 = builderAppendQueryParameter.build().toString();
        Intrinsics.checkNotNullExpressionValue(string2, "toString(...)");
        String str2 = this.d;
        Context context = this.a;
        a aVar = this.g;
        if (aVar == null || (string = aVar.a(context, string2, str2)) == null) {
            string = context.getResources().getString(R.string.share_message, str2, string2);
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        }
        Intent intent = new Intent();
        intent.setAction("android.intent.action.SEND");
        intent.putExtra("android.intent.extra.TEXT", string);
        intent.setType("text/plain");
        return new Pair(intent, string2);
    }
}
