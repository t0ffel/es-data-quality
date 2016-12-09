# Pipeline controller

Pipeline is an object that describes the path of log flow from a specific
source to the warehouse.

## Structure of pipeline:
```
pipeline_metadata:
  id: id of the pipeline (not in scope)
  name: name of the pipeline
  source: string source of the pipeline
  index_pattern: string mask of indices representing a series of indices
  query: query w/o specification of time or index, that uniquely identifies the pipeline data.
  normalizer:
    normalizer section
  collector:
    collector section
  state: open|closed
  data_health: ok|issues|na - defines the health of the data at the query.
```

## Pipeline store

Pipelines are stored in a special index.

## Pipeline controller interface

### Out of pipelines

Report on items not belonging to any pipeline.

### Conflicting pipelines

Report on pipelines that conflict with each other

### Health of data

Report on health of the data per pipeline

### Consistency check

Validate consistency of normalizer/collector vs the query.

## Pipeline actions (not pipeline controller interface)

### Register pipeline

Registers the pipeline with the system.

### Update pipeline

Updates the pipeline
