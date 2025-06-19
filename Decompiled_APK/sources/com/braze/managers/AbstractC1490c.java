package com.braze.managers;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.support.StringUtils;

/* renamed from: com.braze.managers.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract /* synthetic */ class AbstractC1490c {
    public static SharedPreferences a(Context context, String str, String str2, StringBuilder sb, int i) {
        sb.append(StringUtils.getCacheFileSuffix(context, str, str2));
        return context.getSharedPreferences(sb.toString(), i);
    }
}
