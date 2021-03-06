/*-
 * -\-\-
 * Spotify Styx Common
 * --
 * Copyright (C) 2016 Spotify AB
 * --
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -/-/-
 */

package com.spotify.styx.model.deprecated;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.auto.value.AutoValue;
import java.util.Comparator;

/**
 * A value for identifying a {@link Workflow}.
 *
 * <p>This should be used instead of instances of {@link Workflow} in order to make references
 * independent of the current configuration of a {@link Workflow}.
 */
@AutoValue
@Deprecated
public abstract class WorkflowId {

  public static final Comparator<WorkflowId> KEY_COMPARATOR =
      (a, b) -> a.toKey().compareTo(b.toKey());

  @JsonProperty
  public abstract String componentId();

  @JsonProperty
  public abstract String endpointId();

  public String toKey() {
    return componentId() + "#" + endpointId();
  }

  @JsonCreator
  public static WorkflowId create(
      @JsonProperty("component_id") String componentId,
      @JsonProperty("endpoint_id") String id) {
    return new AutoValue_WorkflowId(componentId, id);
  }

  public static WorkflowId create(com.spotify.styx.model.WorkflowId workflowId) {
    return create(workflowId.componentId(), workflowId.id());
  }
}
