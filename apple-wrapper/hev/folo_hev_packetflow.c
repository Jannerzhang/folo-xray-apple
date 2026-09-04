// SPDX-License-Identifier: Apache-2.0

#include "folo_hev_packetflow.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hev-main.h"

enum {
  FOLO_HEV_MAX_CONFIG_BYTES = 64 * 1024,
};

struct hev_context {
  pthread_t thread;
  int thread_created;
  int endpoint_fd;
  unsigned char *config;
  unsigned int config_length;
  int stop_requested;
  int init_done;
  int init_result;
};

static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t state_condition = PTHREAD_COND_INITIALIZER;
static struct hev_context *active_context;
static int state = FOLO_HEV_PACKETFLOW_IDLE;

static void
set_init_result (int result)
{
  pthread_mutex_lock (&state_lock);
  if (active_context) {
    active_context->init_done = 1;
    active_context->init_result = result;
    if (result < 0)
      state = FOLO_HEV_PACKETFLOW_IDLE;
    pthread_cond_broadcast (&state_condition);
  }
  pthread_mutex_unlock (&state_lock);
}

/* Called from the Hev lifecycle boundary, not from a packet callback. */
void
folo_hev_packetflow_init_result (int result)
{
  set_init_result (result);
}

static void *
hev_thread_main (void *opaque)
{
  struct hev_context *context = opaque;
  int result = hev_socks5_tunnel_main_from_str (
      context->config, context->config_length, context->endpoint_fd);

  pthread_mutex_lock (&state_lock);
  if (active_context == context)
    state = FOLO_HEV_PACKETFLOW_IDLE;
  pthread_cond_broadcast (&state_condition);
  pthread_mutex_unlock (&state_lock);

  close (context->endpoint_fd);
  free (context->config);
  context->config = NULL;
  return (void *)(intptr_t)result;
}

int32_t
FoloHevPacketFlowStart (const uint8_t *config_bytes,
                        size_t config_length,
                        int32_t packet_endpoint_fd)
{
  struct hev_context *context;
  int owned_endpoint_fd;
  int result;

  if (!config_bytes || config_length == 0 ||
      config_length > FOLO_HEV_MAX_CONFIG_BYTES || packet_endpoint_fd < 0)
    return FOLO_HEV_PACKETFLOW_INVALID_ARGUMENT;

  /* The caller keeps its descriptor. Hev owns this private duplicate and
   * closes it exactly once from the worker thread, including start failure. */
  owned_endpoint_fd = dup (packet_endpoint_fd);
  if (owned_endpoint_fd < 0)
    return FOLO_HEV_PACKETFLOW_START_FAILED;

  context = calloc (1, sizeof (*context));
  if (!context) {
    close (owned_endpoint_fd);
    return FOLO_HEV_PACKETFLOW_START_FAILED;
  }
  context->config = malloc (config_length);
  if (!context->config) {
    close (owned_endpoint_fd);
    free (context);
    return FOLO_HEV_PACKETFLOW_START_FAILED;
  }
  memcpy (context->config, config_bytes, config_length);
  context->config_length = (unsigned int)config_length;
  context->endpoint_fd = owned_endpoint_fd;

  pthread_mutex_lock (&state_lock);
  if (active_context || state != FOLO_HEV_PACKETFLOW_IDLE) {
    pthread_mutex_unlock (&state_lock);
    close (owned_endpoint_fd);
    free (context->config);
    free (context);
    return FOLO_HEV_PACKETFLOW_INVALID_STATE;
  }
  active_context = context;
  state = FOLO_HEV_PACKETFLOW_STARTING;
  result = pthread_create (&context->thread, NULL, hev_thread_main, context);
  if (result != 0) {
    active_context = NULL;
    state = FOLO_HEV_PACKETFLOW_IDLE;
    pthread_mutex_unlock (&state_lock);
    close (owned_endpoint_fd);
    free (context->config);
    free (context);
    return FOLO_HEV_PACKETFLOW_START_FAILED;
  }
  context->thread_created = 1;

  while (!context->init_done)
    pthread_cond_wait (&state_condition, &state_lock);
  result = context->init_result;
  if (result == 0)
    state = FOLO_HEV_PACKETFLOW_RUNNING;
  pthread_mutex_unlock (&state_lock);

  if (result < 0) {
    pthread_join (context->thread, NULL);
    pthread_mutex_lock (&state_lock);
    active_context = NULL;
    state = FOLO_HEV_PACKETFLOW_IDLE;
    pthread_mutex_unlock (&state_lock);
    free (context);
    return FOLO_HEV_PACKETFLOW_START_FAILED;
  }

  return FOLO_HEV_PACKETFLOW_OK;
}

int32_t
FoloHevPacketFlowStop (void)
{
  struct hev_context *context;

  pthread_mutex_lock (&state_lock);
  context = active_context;
  if (!context) {
    state = FOLO_HEV_PACKETFLOW_IDLE;
    pthread_mutex_unlock (&state_lock);
    return FOLO_HEV_PACKETFLOW_OK;
  }
  state = FOLO_HEV_PACKETFLOW_DRAINING;
  pthread_mutex_unlock (&state_lock);

  hev_socks5_tunnel_quit ();
  if (context->thread_created)
    pthread_join (context->thread, NULL);

  pthread_mutex_lock (&state_lock);
  if (active_context == context)
    active_context = NULL;
  state = FOLO_HEV_PACKETFLOW_IDLE;
  pthread_cond_broadcast (&state_condition);
  pthread_mutex_unlock (&state_lock);
  free (context);
  return FOLO_HEV_PACKETFLOW_OK;
}

int32_t
FoloHevPacketFlowState (void)
{
  int result;
  pthread_mutex_lock (&state_lock);
  result = state;
  pthread_mutex_unlock (&state_lock);
  return result;
}
