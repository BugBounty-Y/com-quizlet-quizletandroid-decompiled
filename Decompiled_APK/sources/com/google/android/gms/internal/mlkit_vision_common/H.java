package com.google.android.gms.internal.mlkit_vision_common;

import com.facebook.FacebookException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;

/* loaded from: classes2.dex */
public abstract class H {
    public static final /* synthetic */ int a = 0;

    public static void a(String identifier) {
        boolean zContains;
        Intrinsics.checkNotNullParameter(identifier, "identifier");
        if (identifier.length() == 0 || identifier.length() > 40) {
            String str = String.format(Locale.ROOT, "Identifier '%s' must be less than %d characters", Arrays.copyOf(new Object[]{identifier, 40}, 2));
            Intrinsics.checkNotNullExpressionValue(str, "format(locale, format, *args)");
            throw new FacebookException(str);
        }
        HashSet hashSet = com.facebook.appevents.e.f;
        synchronized (hashSet) {
            zContains = hashSet.contains(identifier);
            Unit unit = Unit.a;
        }
        if (zContains) {
            return;
        }
        if (!new Regex("^[0-9a-zA-Z_]+[0-9a-zA-Z _-]*$").e(identifier)) {
            throw new FacebookException(androidx.compose.animation.d0.s(new Object[]{identifier}, 1, "Skipping event named '%s' due to illegal name - must be under 40 chars and alphanumeric, _, - or space, and not start with a space or hyphen.", "format(format, *args)"));
        }
        synchronized (hashSet) {
            hashSet.add(identifier);
        }
    }
}
