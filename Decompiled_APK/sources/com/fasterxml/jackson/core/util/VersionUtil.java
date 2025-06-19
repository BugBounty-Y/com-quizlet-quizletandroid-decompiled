package com.fasterxml.jackson.core.util;

import java.util.regex.Pattern;

/* loaded from: classes.dex */
public abstract class VersionUtil {
    private static final Pattern V_SEP = Pattern.compile("[-_./;:]");

    public static final void throwInternal() {
        throw new RuntimeException("Internal error: this code path should never get executed");
    }

    public static final <T> T throwInternalReturnAny() {
        throw new RuntimeException("Internal error: this code path should never get executed");
    }
}
