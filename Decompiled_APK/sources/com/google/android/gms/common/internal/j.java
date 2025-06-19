package com.google.android.gms.common.internal;

import android.content.Context;
import android.content.res.Resources;
import androidx.annotation.NonNull;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public class j {
    public final Resources a;
    public final String b;

    public j(@NonNull Context context) {
        u.h(context);
        Resources resources = context.getResources();
        this.a = resources;
        this.b = resources.getResourcePackageName(R.string.common_google_play_services_unknown_issue);
    }

    public final String a(String str) {
        String str2 = this.b;
        Resources resources = this.a;
        int identifier = resources.getIdentifier(str, "string", str2);
        if (identifier == 0) {
            return null;
        }
        return resources.getString(identifier);
    }
}
