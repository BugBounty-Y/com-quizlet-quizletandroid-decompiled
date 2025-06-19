package assistantMode.refactored.types;

import java.util.Map;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.UnknownFieldException;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.encoding.Decoder;
import kotlinx.serialization.encoding.Encoder;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.D;
import kotlinx.serialization.internal.PluginGeneratedSerialDescriptor;
import org.jetbrains.annotations.NotNull;

@Metadata
@InterfaceC4935d
/* loaded from: classes.dex */
public final class TaskWithProgress$$serializer implements D {

    @NotNull
    public static final TaskWithProgress$$serializer INSTANCE;
    private static final /* synthetic */ PluginGeneratedSerialDescriptor descriptor;

    static {
        TaskWithProgress$$serializer taskWithProgress$$serializer = new TaskWithProgress$$serializer();
        INSTANCE = taskWithProgress$$serializer;
        PluginGeneratedSerialDescriptor pluginGeneratedSerialDescriptor = new PluginGeneratedSerialDescriptor("assistantMode.refactored.types.TaskWithProgress", taskWithProgress$$serializer, 3);
        pluginGeneratedSerialDescriptor.k("progressByQuestionType", false);
        pluginGeneratedSerialDescriptor.k("task", false);
        pluginGeneratedSerialDescriptor.k("totalProgress", false);
        descriptor = pluginGeneratedSerialDescriptor;
    }

    private TaskWithProgress$$serializer() {
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] childSerializers() {
        return new KSerializer[]{TaskWithProgress.d[0], Task$$serializer.INSTANCE, TaskProgress$$serializer.INSTANCE};
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public TaskWithProgress deserialize(@NotNull Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.a aVarC = decoder.c(descriptor2);
        KSerializer[] kSerializerArr = TaskWithProgress.d;
        Map map = null;
        boolean z = true;
        int i = 0;
        Task task = null;
        TaskProgress taskProgress = null;
        while (z) {
            int iT = aVarC.t(descriptor2);
            if (iT == -1) {
                z = false;
            } else if (iT == 0) {
                map = (Map) aVarC.z(descriptor2, 0, kSerializerArr[0], map);
                i |= 1;
            } else if (iT == 1) {
                task = (Task) aVarC.z(descriptor2, 1, Task$$serializer.INSTANCE, task);
                i |= 2;
            } else {
                if (iT != 2) {
                    throw new UnknownFieldException(iT);
                }
                taskProgress = (TaskProgress) aVarC.z(descriptor2, 2, TaskProgress$$serializer.INSTANCE, taskProgress);
                i |= 4;
            }
        }
        aVarC.b(descriptor2);
        return new TaskWithProgress(i, map, task, taskProgress);
    }

    @Override // kotlinx.serialization.KSerializer
    @NotNull
    public SerialDescriptor getDescriptor() {
        return descriptor;
    }

    @Override // kotlinx.serialization.KSerializer
    public void serialize(@NotNull Encoder encoder, @NotNull TaskWithProgress value) {
        Intrinsics.checkNotNullParameter(encoder, "encoder");
        Intrinsics.checkNotNullParameter(value, "value");
        SerialDescriptor descriptor2 = getDescriptor();
        kotlinx.serialization.encoding.b bVarC = encoder.c(descriptor2);
        bVarC.i(descriptor2, 0, TaskWithProgress.d[0], value.a);
        bVarC.i(descriptor2, 1, Task$$serializer.INSTANCE, value.b);
        bVarC.i(descriptor2, 2, TaskProgress$$serializer.INSTANCE, value.c);
        bVarC.b(descriptor2);
    }

    @Override // kotlinx.serialization.internal.D
    @NotNull
    public KSerializer[] typeParametersSerializers() {
        return AbstractC5047c0.b;
    }
}
