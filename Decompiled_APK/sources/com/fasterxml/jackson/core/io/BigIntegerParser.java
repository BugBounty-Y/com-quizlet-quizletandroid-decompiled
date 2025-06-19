package com.fasterxml.jackson.core.io;

import android.support.v4.media.session.a;
import com.fasterxml.jackson.core.internal.shaded.fdp.v2_19_0.JavaBigIntegerParser;
import java.math.BigInteger;

/* loaded from: classes.dex */
public abstract class BigIntegerParser {
    public static BigInteger parseWithFastParser(String str) {
        try {
            return JavaBigIntegerParser.parseBigInteger(str);
        } catch (NumberFormatException e) {
            if (str.length() > 1000) {
                str = str.substring(0, 1000) + " [truncated]";
            }
            StringBuilder sbY = a.y("Value \"", str, "\" can not be represented as `java.math.BigInteger`, reason: ");
            sbY.append(e.getMessage());
            throw new NumberFormatException(sbY.toString());
        }
    }
}
