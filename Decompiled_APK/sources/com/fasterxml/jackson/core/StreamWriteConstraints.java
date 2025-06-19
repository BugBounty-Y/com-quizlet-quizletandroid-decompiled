package com.fasterxml.jackson.core;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.core.exc.StreamConstraintsException;
import java.io.Serializable;

/* loaded from: classes.dex */
public class StreamWriteConstraints implements Serializable {
    private static StreamWriteConstraints DEFAULT = new StreamWriteConstraints(1000);
    protected final int _maxNestingDepth;

    public StreamWriteConstraints(int i) {
        this._maxNestingDepth = i;
    }

    public static StreamWriteConstraints defaults() {
        return DEFAULT;
    }

    public String _constrainRef(String str) {
        return a.B("`StreamWriteConstraints.", str, "()`");
    }

    public StreamConstraintsException _constructException(String str, Object... objArr) throws StreamConstraintsException {
        throw new StreamConstraintsException(String.format(str, objArr));
    }

    public void validateNestingDepth(int i) throws StreamConstraintsException {
        if (i > this._maxNestingDepth) {
            throw _constructException("Document nesting depth (%d) exceeds the maximum allowed (%d, from %s)", Integer.valueOf(i), Integer.valueOf(this._maxNestingDepth), _constrainRef("getMaxNestingDepth"));
        }
    }
}
