package com.quizlet.features.setpage.terms;

import com.quizlet.remote.exceptions.NetException;
import java.util.Objects;
import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class RefreshTermAndSelectedTermException extends RuntimeException {
    public final boolean a;

    public RefreshTermAndSelectedTermException(NetException netException) {
        super(netException);
        this.a = Objects.nonNull(netException);
    }
}
