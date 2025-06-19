package com.braze.events;

import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public interface IEventSubscriber<T> {
    void trigger(T t);
}
