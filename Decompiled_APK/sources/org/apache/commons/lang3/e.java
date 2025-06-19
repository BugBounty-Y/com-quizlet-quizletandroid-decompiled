package org.apache.commons.lang3;

import android.text.SpannableStringBuilder;
import java.util.Collection;
import java.util.Iterator;
import java.util.Spliterators;
import java.util.StringJoiner;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/* loaded from: classes3.dex */
public abstract class e {
    static {
        Pattern.compile("\\p{InCombiningDiacriticalMarks}+");
    }

    public static int a(SpannableStringBuilder spannableStringBuilder, CharSequence charSequence) {
        if (spannableStringBuilder == charSequence) {
            return -1;
        }
        int i = 0;
        if (spannableStringBuilder != null && charSequence != null) {
            while (i < spannableStringBuilder.length() && i < charSequence.length() && spannableStringBuilder.charAt(i) == charSequence.charAt(i)) {
                i++;
            }
            if (i >= charSequence.length() && i >= spannableStringBuilder.length()) {
                return -1;
            }
        }
        return i;
    }

    public static boolean b(CharSequence charSequence) {
        int length = charSequence == null ? 0 : charSequence.length();
        if (length == 0) {
            return true;
        }
        for (int i = 0; i < length; i++) {
            if (!Character.isWhitespace(charSequence.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    public static boolean c(CharSequence charSequence) {
        return charSequence == null || charSequence.length() == 0;
    }

    public static boolean d(CharSequence charSequence) {
        return !b(charSequence);
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [org.apache.commons.lang3.stream.a] */
    public static String e(final String str, Collection collection) {
        Iterator it2;
        if (collection == null || (it2 = collection.iterator()) == null) {
            return null;
        }
        if (!it2.hasNext()) {
            return "";
        }
        Stream stream = StreamSupport.stream(Spliterators.spliteratorUnknownSize(it2, 16), false);
        new com.fasterxml.jackson.databind.introspect.a(1);
        return (String) stream.collect(new org.apache.commons.lang3.stream.d(new Supplier() { // from class: org.apache.commons.lang3.stream.a
            @Override // java.util.function.Supplier
            public final Object get() {
                return new StringJoiner(str, "", "");
            }
        }, new org.apache.commons.lang3.stream.b(), new org.apache.commons.lang3.stream.c(), new com.fasterxml.jackson.databind.introspect.a(2), org.apache.commons.lang3.stream.e.a));
    }
}
