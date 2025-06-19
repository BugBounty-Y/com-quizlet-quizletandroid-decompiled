package com.google.android.gms.internal.ads;

import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public abstract class DB {
    public static final Pattern a = Pattern.compile("bytes (\\d+)-(\\d+)/(?:\\d+|\\*)");
    public static final Pattern b = Pattern.compile("bytes (?:(?:\\d+-\\d+)|\\*)/(\\d+)");
}
