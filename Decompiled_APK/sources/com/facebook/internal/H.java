package com.facebook.internal;

import androidx.compose.animation.d0;
import java.io.File;
import java.io.FilenameFilter;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;

/* loaded from: classes.dex */
public final /* synthetic */ class H implements FilenameFilter {
    public final /* synthetic */ int a;

    public /* synthetic */ H(int i) {
        this.a = i;
    }

    @Override // java.io.FilenameFilter
    public final boolean accept(File file, String name) {
        switch (this.a) {
            case 0:
                return Pattern.matches("cpu[0-9]+", name);
            case 1:
                Intrinsics.checkNotNullExpressionValue(name, "name");
                return new Regex(d0.s(new Object[]{"crash_log_", "shield_log_", "thread_check_log_"}, 3, "^(%s|%s|%s)[0-9]+.json$", "format(format, *args)")).e(name);
            case 2:
                Intrinsics.checkNotNullExpressionValue(name, "name");
                return new Regex(d0.s(new Object[]{"anr_log_"}, 1, "^%s[0-9]+.json$", "format(format, *args)")).e(name);
            case 3:
                Intrinsics.checkNotNullExpressionValue(name, "name");
                return new Regex(d0.s(new Object[]{"analysis_log_"}, 1, "^%s[0-9]+.json$", "format(format, *args)")).e(name);
            case 4:
                Intrinsics.checkNotNullExpressionValue(name, "name");
                return new Regex(d0.s(new Object[]{"error_log_"}, 1, "^%s[0-9]+.json$", "format(format, *args)")).e(name);
            case 5:
                return name.startsWith("aqs.");
            case 6:
                return name.startsWith(".ae");
            case 7:
                return name.startsWith("event");
            default:
                return name.startsWith("event") && !name.endsWith("_");
        }
    }
}
