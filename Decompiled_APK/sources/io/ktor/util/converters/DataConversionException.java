package io.ktor.util.converters;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public class DataConversionException extends Exception {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public DataConversionException() {
        super("Invalid data format");
        Intrinsics.checkNotNullParameter("Invalid data format", "message");
    }
}
