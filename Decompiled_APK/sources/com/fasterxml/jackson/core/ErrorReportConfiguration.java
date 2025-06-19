package com.fasterxml.jackson.core;

import com.pubmatic.sdk.video.a;
import java.io.Serializable;

/* loaded from: classes.dex */
public class ErrorReportConfiguration implements Serializable {
    private static ErrorReportConfiguration DEFAULT = new ErrorReportConfiguration(256, a.GENERAL_NONLINEAR_AD_ERROR);
    protected final int _maxErrorTokenLength;
    protected final int _maxRawContentLength;

    public ErrorReportConfiguration(int i, int i2) {
        this._maxErrorTokenLength = i;
        this._maxRawContentLength = i2;
    }

    public static ErrorReportConfiguration defaults() {
        return DEFAULT;
    }

    public int getMaxErrorTokenLength() {
        return this._maxErrorTokenLength;
    }

    public int getMaxRawContentLength() {
        return this._maxRawContentLength;
    }
}
