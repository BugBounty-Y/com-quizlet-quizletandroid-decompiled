package com.quizlet.data.repository.course.exceptions;

import java.io.IOException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class CreateDuplicatedCourseException extends IOException {
    public final String a;
    public final String b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CreateDuplicatedCourseException(String name, String code) {
        super("This course already exists");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(code, "code");
        this.a = name;
        this.b = code;
    }
}
