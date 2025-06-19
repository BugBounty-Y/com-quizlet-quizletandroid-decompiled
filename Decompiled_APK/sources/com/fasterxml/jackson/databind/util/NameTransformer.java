package com.fasterxml.jackson.databind.util;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import java.io.Serializable;

/* loaded from: classes.dex */
public abstract class NameTransformer {
    public static final NameTransformer NOP = new NopTransformer();

    public static class Chained extends NameTransformer implements Serializable {
        protected final NameTransformer _t1;
        protected final NameTransformer _t2;

        public Chained(NameTransformer nameTransformer, NameTransformer nameTransformer2) {
            this._t1 = nameTransformer;
            this._t2 = nameTransformer2;
        }

        public String toString() {
            return "[ChainedTransformer(" + this._t1 + ", " + this._t2 + ")]";
        }

        @Override // com.fasterxml.jackson.databind.util.NameTransformer
        public String transform(String str) {
            return this._t1.transform(this._t2.transform(str));
        }
    }

    public static final class NopTransformer extends NameTransformer implements Serializable {
        @Override // com.fasterxml.jackson.databind.util.NameTransformer
        public String transform(String str) {
            return str;
        }
    }

    public static NameTransformer chainedTransformer(NameTransformer nameTransformer, NameTransformer nameTransformer2) {
        return new Chained(nameTransformer, nameTransformer2);
    }

    public static NameTransformer simpleTransformer(final String str, final String str2) {
        boolean z = false;
        boolean z2 = (str == null || str.isEmpty()) ? false : true;
        if (str2 != null && !str2.isEmpty()) {
            z = true;
        }
        return z2 ? z ? new NameTransformer() { // from class: com.fasterxml.jackson.databind.util.NameTransformer.1
            public String toString() {
                StringBuilder sb = new StringBuilder("[PreAndSuffixTransformer('");
                sb.append(str);
                sb.append("','");
                return a.t(sb, str2, "')]");
            }

            @Override // com.fasterxml.jackson.databind.util.NameTransformer
            public String transform(String str3) {
                return str + str3 + str2;
            }
        } : new NameTransformer() { // from class: com.fasterxml.jackson.databind.util.NameTransformer.2
            public String toString() {
                return a.t(new StringBuilder("[PrefixTransformer('"), str, "')]");
            }

            @Override // com.fasterxml.jackson.databind.util.NameTransformer
            public String transform(String str3) {
                return a.t(new StringBuilder(), str, str3);
            }
        } : z ? new NameTransformer() { // from class: com.fasterxml.jackson.databind.util.NameTransformer.3
            public String toString() {
                return a.t(new StringBuilder("[SuffixTransformer('"), str2, "')]");
            }

            @Override // com.fasterxml.jackson.databind.util.NameTransformer
            public String transform(String str3) {
                StringBuilder sbU = d0.u(str3);
                sbU.append(str2);
                return sbU.toString();
            }
        } : NOP;
    }

    public abstract String transform(String str);
}
